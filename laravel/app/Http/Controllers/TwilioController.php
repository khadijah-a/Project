<?php

namespace App\Http\Controllers;

use App\Services\UrlAnalysisService;
use Illuminate\Http\Request;
use Twilio\TwiML\MessagingResponse;
use Illuminate\Support\Facades\Log;
use Twilio\Rest\Client;
class TwilioController extends Controller
{
    protected $urlAnalysisService;
 

    public function __construct(ViresTotal $urlAnalysisService)
    {
        $this->urlAnalysisService = $urlAnalysisService;
    }

    public function handleIncomingMessage(Request $request)
    {   ob_end_clean(); // Flush the output buffer
        header("Connection: close");
        ignore_user_abort(true);
        http_response_code(200);
        ob_start();
        echo 'OK';
        $size = ob_get_length();
        header("Content-Length: $size");
        ob_end_flush();
        flush();


        
        set_time_limit(seconds: 600);

        // Log the entire incoming request for debugging purposes
        Log::info($request->all());
    
        // Extract the message body from the request (assuming it's in the 'Body' key)
        $requestBody = $request->input('Body');
        Log::info("Received message: " . $requestBody);
    
        // Check if the message body is a valid URL
        if (!filter_var($requestBody, FILTER_VALIDATE_URL)) {
            $result = " *العنوان الذي أرسلته غير صالح*\nيرجى التحقق من صحة الرابط وإعادة المحاولة.";
            $this->sendWhatsAppMessage($request->input('From'), $result);
            Log::info("Invalid URL received: " . $requestBody);
        } else {
            // If it's a valid URL, call the URL analysis service to analyze the URL
            $result = "نقوم بتحليل ، الرابط الرجاء الانتظار. قليلاً";
            $this->sendWhatsAppMessage($request->input('From'), $result);
            
        
            $resultBody = $this->urlAnalysisService->analyzeUrl($requestBody);
    
            // Log the raw result for debugging
            Log::info("Raw result from analyzeUrl: " . $resultBody);
    
            // Use a regular expression to remove HTTP headers and keep only the JSON body
            $jsonPart = preg_replace('/^.*\r?\n\r?\n/s', '', $resultBody);  // Strip out the headers
    
            // Log the extracted JSON part
            Log::info("Extracted JSON: " . $jsonPart);
    
            // Try to decode the extracted JSON
            $decodedResult = json_decode($jsonPart, true);  // Decoding as an associative array
    
            // Check if decoding was successful and if it is an array
            if (json_last_error() === JSON_ERROR_NONE && is_array($decodedResult)) {
                
                $result = 'نقوم بتحليل ، الرابط الرجاء الانتظار. قليلاً';
                 $resultEnd = $this->handleThreatAnalysisArray($decodedResult); 

               foreach ($resultEnd as $messagePart) {
            $this->sendWhatsAppMessage($request->input('From'), $messagePart);
            sleep(1);  // Delay to avoid rapid consecutive messages (optional)
        }
                 
            } else {
                // Log the decoding error and return an error message
                Log::error("JSON decode error: " . json_last_error_msg());
                Log::error("Failed to decode JSON part: " . $jsonPart);
                $result = "Error decoding the analysis result.";
            }
        }
    
        Log::info(message: "Final result: " . $result);
    
        //Create a Twilio MessagingResponse to reply back
       $response = new MessagingResponse();
       $response->message($result)->__tostring();
      Log::info(message: "Massege: " . $response);

        // Return the Twilio response as XML
       return $response;
      }

    private function handleThreatAnalysisArray($data)
    {
        Log::info('Handling threat analysis array: ' . json_encode($data));
        $summaryParts = [];
        $staticState = 'Harmless';  // Default static state
    
        // Check if there's a 400 error in the first part of the response
        if (isset($data[0]['error'])) {
            // Only proceed with the second part if it exists
            $summaryParts[] =  " ____________________\n". "معلـــومات عــن انواع التــحلــل \n".  " ____________________\n". 
                "تحليل ثابت: تم فحص الرمز والعناصر المكونة للرابط للتحقق من أي إشارات مـــــــشــــبوههة.\n" .
                "تحليل ديناميكي: تم اختبار الرابط في بيئة آمنة لمراقبة سلوكه عند الوصول إليه.\n" .
                "بيئة الاختبار: Windows 10 64-bit.\n" .
                " ____________________\n". "النتيجه\n".  " ____________________\n";
    
            if (isset($data[1])) {
                $maliciousCount = $data[1]['malicious'] ?? 0;
                $suspiciousCount = $data[1]['suspicious'] ?? 0;
    
                $analysisResult = $maliciousCount > 0 ? 'malicious' : ($suspiciousCount > 0 ? 'suspicious' : 'harmless');
                $summaryParts[] = "نتائج تحليل الأخيره : $analysisResult \n";
                $summaryParts[] = "يرجى التحقق من مصدر الرابط قبل النقر عليه،توخَّ الحذر وتأكد من أنه من مصدر موثوق.\n";
            }
        } else {
            // Process the detailed threat analysis if no 400 error is present
            if (isset($data[0]['original'])) {
                $staticAnalysis = $data[0]['original'];
                $classificationTags = $staticAnalysis['classification_tags'] ?? [];
                $verdict = $staticAnalysis['verdict'] ?? 'Unknown verdict';
                $threatScore = $staticAnalysis['threat_score'] ?? 0;
                $avDetect = $staticAnalysis['AV_detect'] ?? 0;
                $totalSignatures = $staticAnalysis['total_signatures'] ?? 0;
                $totalNetworkConnections = $staticAnalysis['total_network_connections'] ?? 0;
                $totalProcesses = $staticAnalysis['total_processes'] ?? 0;
    
                $summaryParts[] = "شكرا للإنتظار لقد قمنا بتحليل الرابط الذي أرسلته\n";
                $classification = $classificationTags ? implode(', ', $classificationTags) : "لا يوجد تصنيف للرابط";

                $summaryParts[] =  "__________________________ \n". "معلـــومات عــن انواع التــحلــل \n".  " __________________________\n".
                    "تحليل ثابت: تم فحص الرمز والعناصر المكونة للرابط للتحقق من أي إشارات مـــــــشــــبوههة.\n" .
                    "تحليل ديناميكي: تم اختبار الرابط في بيئة آمنة لمراقبة سلوكه عند الوصول إليه.\n" .
                    "بيئة الاختبار: Windows 10 64-bit.\n" ;
                  
                
                if (isset($data[1])) {
                        $maliciousCount = $data[1]['malicious'] ?? 0;
                        $suspiciousCount = $data[1]['suspicious'] ?? 0;
                    

                        $summaryParts[] =   " ____________________\n". "النتـــيجه\n".  " ____________________\n". 
                        "التصنيف: " . $classification . "\n" .
                        "درجة التهديد: $threatScore%\n" ;
               
                   if ($maliciousCount == 0 && $suspiciousCount == 0) {
                        if ($verdict === 'malicious') {
                            $summaryParts[] = "نتائج تحليل الأخيره : خبـــيــــث \n";
                        } elseif ($verdict === 'suspicious') {
                            $summaryParts[] = "نتائج تحليل الأخيره : مـــــــشــــبوهه \n";
                        } else {
                            $summaryParts[] = "نتائج تحليل الأخيره : آمــــــن \n";
                        }

                    } elseif ($maliciousCount < $suspiciousCount) {
                       
                        if ( $verdict === 'malicious') {
                            $summaryParts[] = "نتائج تحليل الأخيره : خبـــيــــث \n";
                        } elseif ($verdict === 'suspicious') {
                            $summaryParts[] = "نتائج تحليل الأخيره : مـــــــشــــبوهه \n";
                        } else {
                            $summaryParts[] = "نتائج تحليل الأخيره : مـــــــشــــبوهه \n";
                        } 

                    } elseif ($maliciousCount > $suspiciousCount) {
                       
                        if ($verdict === 'malicious') {
                            $summaryParts[] = "نتائج تحليل الأخيره :  خبـــيــــث \n";
                        } elseif ( $verdict === 'suspicious') {
                            $summaryParts[] = "نتائج تحليل الأخيره :  خبـــيــــث \n";
                        } else {
                            $summaryParts[] = "نتائج تحليل الأخيره :  خبـــيــــث \n";
                        }
                    } elseif($maliciousCount == $suspiciousCount){
                        
                        if ( $verdict === 'malicious') {
                            $summaryParts[] = "نتائج تحليل الأخيره :  خبـــيــــث \n";
                        } elseif ($verdict === 'suspicious') {
                            $summaryParts[] = "نتائج تحليل الأخيره :  خبـــيــــيث \n";
                        } else {
                            $summaryParts[] = "نتائج تحليل الأخيره :  خبـــيــــث \n";
                        }
                    }
             

                }
    
                
                $summaryParts[] =  " ____________________\n". "للمــزيـد من التفـاصيــل \n".  " ____________________\n".
                "$avDetect من برامج مضادة للفيروسات اكتشفت اشتباه تهديد.\n" .
                    "تم العثور على $totalSignatures توقيعًا يحتمل أن يكون تهديدًا.\n" .
                    "تم العثور على $totalNetworkConnections اتصالًا بالشبكة.\n" .
                    "تم العثور على $totalProcesses عملية تم تشغيلها أثناء التحليل الديناميكي.\n";
               
               
                    $counter = 1;

                if (!empty($staticAnalysis['signatures']) && is_array($staticAnalysis['signatures'])) {
                    $signatureDetails = "كانت العمليات المـــــــشــــبوهه على النحو التالي:\n\n";
                    foreach ($staticAnalysis['signatures'] as $signature) {
                        //display only suspicious and malicious process
                        if ($signature['threat_level_human'] === 'suspicious' || $signature['threat_level_human'] === 'malicious') {
                            $signatureDetails .= $counter . ".  " . ($signature['name'] ?? 'Unknown signature') . "\n";
                            $counter=$counter+1; 
                        }
                    }
                    $summaryParts[] = $signatureDetails;
                } else {
                    $summaryParts[] = "\n العملـــــيات المشـــبـــوة : لايوجد عمليات مشبوه \n";
                }
            }
        }
       
    
        // Add security recommendations
        $summaryParts[] =" ____________________\n". "توصــيـــــات\n".  " ____________________\n".
         "نوصي بشدة باتخاذ التدابير الوقائية التالية:\n" .
            "1. عدم النقر على الروابط غير الموثوقة.\n" .
            "2. تحديث برامج الحماية بانتظام.\n" .
            "3. تجنب تنزيل الملفات غير الموثوقة.\n" .
            "4. فحص الروابط قبل فتحها.\n" .
            "5. تجاهل الرسائل التي تطلب معلومات شخصية أو مالية بشكل غير عادي.\n" .
            "6. إنشاء نسخ احتياطية من بيانات هاتفك بانتظام.\n" .
            "اتباع هذه الخطوات يمكن أن يساعد في حماية معلوماتك الشخصية من التهديدات الإلكترونية.\n";
    
        Log::info('Final message parts generated: ' . json_encode($summaryParts));
        return $summaryParts;
    }
    
private function sendWhatsAppMessage($to, $body)
{
    $sid = 'AC4f19643ec3522bb7146a7c441e02cd0f';
    $token = 'ad16611189006f18750250b8bd2ca98c';
    $twilio = new Client($sid, $token);

    $fromWhatsAppNumber = 'whatsapp:+14155238886';
   //$to = 'whatsapp:+0000000000000';
    Log::info('phone number ' . $to);
    try {
        $message = $twilio->messages->create(
            $to,
            [
                'from' => $fromWhatsAppNumber,
                'body' => $body
            ]
        );
        Log::info("WhatsApp message sent, SID: " . $message->sid);
    } catch (\Exception $e) {
        Log::error("Failed to send WhatsApp message: " . $e->getMessage());
    }
}
}