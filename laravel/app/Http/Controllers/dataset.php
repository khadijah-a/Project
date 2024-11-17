<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use GuzzleHttp\Client;

class dataset extends Controller
{

    private $baseUrlHybired = 'https://www.hybrid-analysis.com/api/v2';
    private $baseUrl;

    // Analyze URL using VirusTotal
    public function analyzeUrlVirusTotal($url)
    {
        // Extend the script execution time to handle long requests
        ini_set('max_execution_time', 3000);

        // Retrieve your VirusTotal API key from the .env file
        $apiKey = env('VIRUSTOTAL_API_KEY');
        $client = new Client();
        $this->baseUrl = 'https://www.virustotal.com/api/v3'; // VirusTotal API v3

        try {
            // Submit URL for analysis
            $submissionResponse = $client->request('POST', $this->baseUrl . '/urls', [
                'headers' => [
                    'x-apikey' => 'f8ff26872b3fb38c2c4aee88691304f041543091d3dd667524e99a77025fc18c',
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'form_params' => [
                    'url' => $url,
                ],
            ]);

            $submissionBody = json_decode($submissionResponse->getBody(), true);

            if (!isset($submissionBody['data']['id'])) {
                return response()->json(['error' => 'Failed to submit URL for analysis'], 400);
            }

            $reportId = $submissionBody['data']['id'];

            // Poll the analysis state until it's completed
            do {
                $statusResponse = $client->request('GET', $this->baseUrl . "/analyses/{$reportId}", [
                    'headers' => [
                        'x-apikey' => 'f8ff26872b3fb38c2c4aee88691304f041543091d3dd667524e99a77025fc18c',
                        'accept' => 'application/json',
                    ],
                ]);

                $statusBody = json_decode($statusResponse->getBody(), true);

                if (isset($statusBody['error'])) {
                    return response()->json(['error' => 'Failed to retrieve analysis state'], 400);
                }

                $state = $statusBody['data']['attributes']['status'];

                sleep(10);
            } while ($state != 'completed'); // Repeat until the analysis is completed

            // Retrieve the analysis result
            $resultResponse = $client->request('GET', $this->baseUrl . "/analyses/{$reportId}", [
                'headers' => [
                    'x-apikey' => 'f8ff26872b3fb38c2c4aee88691304f041543091d3dd667524e99a77025fc18c',
                    'accept' => 'application/json',
                ]
            ]);

            $resultBody = json_decode($resultResponse->getBody(), true);
            $last = $resultBody['data']['attributes']['stats'];



          

            return $last; // Return result directly for further processing

        } catch (\Exception $e) {
            return ['error' => 'Failed to analyze the URL', 'message' => $e->getMessage()];
        }
    }

    // Analyze URL using Hybrid Analysis
    public function HybridAnalysisScanUrl($url)
    {
        //set_time_limit(600);
        $apiKey = env('HYBRID_ANALYSIS_API_KEY');
        $client = new Client();
        ini_set('max_execution_time', 3000); // Increase to 60 seconds
        try {
            // Submit URL for analysis
            $submissionResponse = $client->request('POST', $this->baseUrlHybired . '/submit/url', [
                'form_params' => [
                    'url' => $url,
                    'environment_id' => 160,
                    'custom_run_time' => 360
                ],
                'headers' => [
                    'accept' => 'application/json',
                    'content-type' => 'application/x-www-form-urlencoded',
                    'api-key' => 'k5152a7h6f53ed65enk3re3p0efda626ateoh202ffe6f96c3r1tupqrfc2de219',
                ],
            ]);

            // sleep(120);
            $submissionBody = json_decode($submissionResponse->getBody(), true);

            if (!isset($submissionBody['job_id'])) {
                return ['error' => 'Failed to submit URL for analysis'];
            }

            $reportId = $submissionBody['job_id'];
            if ($submissionResponse) {
                do {
                    sleep(20);
                    $statusResponse = $client->request('GET', $this->baseUrlHybired . "/report/{$reportId}/state", [
                        'headers' => [
                            'accept' => 'application/json',
                            'content-type' => 'application/x-www-form-urlencoded',
                            'api-key' => 'k5152a7h6f53ed65enk3re3p0efda626ateoh202ffe6f96c3r1tupqrfc2de219',
                        ],
                    ]);

                    $statusBody = json_decode($statusResponse->getBody(), true);

                    if (isset($statusBody['error']) || $statusBody['state'] == 'ERROR') {
                        return ['error' => 'Failed to retrieve analysis state'];
                    }

                    $state = $statusBody['state'];
                } while ($state != 'SUCCESS');
            }

            // Retrieve the analysis result
            $resultResponse = $client->request('GET', $this->baseUrlHybired . "/report/{$reportId}/summary", [
                'headers' => [
                    'api-key' => 'k5152a7h6f53ed65enk3re3p0efda626ateoh202ffe6f96c3r1tupqrfc2de219',
                    'accept' => 'application/json',
                ]
            ]);

            $resultBody = json_decode($resultResponse->getBody(), true);
      

            // 5. Add signatures to the response array

            // Return the final JSON response
            return $resultBody['verdict'];
        } catch (\Exception $e) {
            return ;
        }
    }


    public function analyzeUrl()
    {

        $urls = [
            'https://ar2019042.page.link/iGuj',
            'https://new-serve00.square.site/',
            'https://docs.google.com/presentation/d/e/2PACX-1vSv2b1uHNEaJ9TrThg4Eo6mYwumo0SOo7IfWYj8MNtJOklrqMVsB_UODFT0MvrgwougzKUSGBMjxw6k/pub?start=false&loop=false&delayms=3000',
            'https://plainocentratippro.pages.dev',
            'https://www6.claims-aethirs.com',
            'https://manlta.net',
            'https://martamaskwallt.gitbook.io',
            'https://vipstoretw.com',
            'https://max1382.com',
            'https://safra.syncnow-app.com',
            'http://9779.info/%E6%AF%9B%E7%BA%BF%E8%B4%B4%E7%94%BB%20%E5%9C%BA%E6%99%AF%E5%9B%BE/',
            'http://style.org.hc360.com/css/detail/mysite/siteconfig/pro_control.css',
            'http://9779.info/%E6%89%8B%E5%B7%A5%E6%B2%BE%E8%B4%B4%E7%94%BB%E5%9B%BE%E7%89%87/',
            'http://www.ghostwriting.de/rueckruf',
            'http://www.pashminaonline.com/pure-pashminas',
            'http://img14.360buyimg.com/n12/g12/M00/07/06/rBEQYVGV9NMIAAAAAAC3mn17ud8AABZ_wDjtTAAALey000.jpg%21q70.jpg',
            'http://portal.dddgaming.com/docs/rules/15022/cn/game_cn.html?amluMjAxNQ%3D%3D',
            'https://bio.site/atttt',
            'https://binghaam00.wixsite.com/my-site-1',
            'https://hopeful-reservation-501216.framer.app/',
            'https://afton4784.hocoos.com/',
            'https://form.jotform.com/243035396100043',
            'http://bradescoprime.com.ua/promotion/acesso/',
            'https://mally912.wixsite.com/dferr',
            'https://attlampl.weebly.com/',
            'https://aattt573f.weebly.com/',
            'https://system-outlookpl.us-lax-1.linodeobjects.com/officeemailsp96087',
            'https://uyktjfkyydrjsertkreh.weebly.com/',
            'http://refund-1inch.site',
            'https://servespay.xyz/login',
            'https://mzansionlyfans.co.za/ps',
            'https://flaretrustline.cc/connect.html',
            'https://contactobhd.glitch.me/',
            'http://www.szabadmunkaero.hu/cimoldal.html?start=12',
            'http://www.kingsmillshotel.com/spring/mothers-day',
            'http://www.approvi.com.br/ck.htm',
            'http://www.myenrg.com/southwest/9-texas',
            'http://www.musimagen.com/lista_socios.php?letra=%C3%91',
            'http://www.ligermedia.co.th/th/about-us.html',
            'http://puracolombia.com/en/company',
            'http://www.creuzadema.net/chiara-jeri',
            'http://www.istracentrum.sk/fotogalerie/94-fotoforum-2012/detail/1601-dscn2316?tmpl=component',
            'http://www.latarnik.eu/index.php?option=com_contact&view=contact&id=1&Itemid=10',
            'http://www.nfa.com.tr/index.php?option=com_content&view=article&id=80&Itemid=128',
            'http://peluqueriadeautor.com/index.php?option=com_virtuemart&page=shop.feed&category_id=6&Itemid=70',
            'http://mp3raid.com/music/krizz_kaliko.html',
            'http://bopsecrets.org/rexroth/cr/1.htm',
            'http://buzzfil.net/m/show-art/ils-etaient-loin-de-s-imaginer-que-le-hibou-allait-faire-ceci-quand-ils-filmaient-2.html',
            'https://corporationwiki.com/Ohio/Columbus/frank-s-benson-P3333917.aspx',
            'https://myspace.com/video/vid/30602581',
            'https://nugget.ca/ArticleDisplay.aspx?archive=true&e=1160966',
            'https://uk.linkedin.com/pub/steve-rubenstein/8/718/755',
            'https://lbpiaccess.com',
            'https://casamanana.org/education/blba/',
            'https://psychology.wikia.com/wiki/Phonemes',
            'http://articles.baltimoresun.com/1991-06-11/sports/1991162162_1_james-koehler-texas-rangers-terrell-lowery',
            'https://spoke.com/dir/p/desantis/nick',
            'hxxps://noor.moe.gov.sa/Noor/Login.aspx',
            'hxxps://beta.madrasati.sa/',
            'hxxps://ieeexplore.ieee.org/Xplore/home.jsp',
            'https://owasp.org/',
        ];
        // First, get the Hybrid Analysis result

        $results = [];

        // Loop through each URL and analyze it
        foreach ($urls as $url) {
            // Get Hybrid Analysis result for the current URL
            $hybridResult = $this->HybridAnalysisScanUrl($url);
           
            $virusTotalResult = $this->analyzeUrlVirusTotal($url);
 
            if (isset($virusTotalResult)) {
                $maliciousCount = $virusTotalResult['malicious'] ?? 0;
                $suspiciousCount = $virusTotalResult['suspicious'] ?? 0;
            
                // Determine the static analysis sta
            $summaryParts = []; 
       
           if ($maliciousCount == 0 && $suspiciousCount == 0) {
                if ($hybridResult === 'malicious') {
                    $summaryParts[] = "نتائج تحليل الأخيره : malicious \n";
                } elseif ($hybridResult === 'suspicious') {
                    $summaryParts[] = "نتائج تحليل الأخيره : suspicious \n";
                } else {
                    $summaryParts[] = "نتائج تحليل الأخيره : harmless \n";
                }
            } elseif ($maliciousCount < $suspiciousCount) {
                if ( $hybridResult === 'malicious') {
                    $summaryParts[] = "نتائج تحليل الأخيره : malicious \n";
                } elseif ($hybridResult === 'suspicious') {
                    $summaryParts[] = "نتائج تحليل الأخيره : suspicious \n";
                } else {
                    $summaryParts[] = "نتائج تحليل الأخيره : suspicious \n";
                } 
            } elseif ($maliciousCount > $suspiciousCount) {
                if ( $hybridResult === 'malicious') {
                    $summaryParts[] = "نتائج تحليل الأخيره : malicious \n";
                } elseif ($hybridResult === 'suspicious') {
                    $summaryParts[] = "نتائج تحليل الأخيره : malicious \n";
                } else {
                    $summaryParts[] = "نتائج تحليل الأخيره : malicious \n";
                }
            } elseif($maliciousCount == $suspiciousCount){
                if ( $hybridResult === 'malicious') {
                    $summaryParts[] = "نتائج تحليل الأخيره : malicious \n";
                } elseif ($hybridResult === 'suspicious') {
                    $summaryParts[] = "نتائج تحليل الأخيره : malicious \n";
                } else {
                    $summaryParts[] = "نتائج تحليل الأخيره : malicious \n";
                }
            }
              
        }
            sleep(4);
                $results[] = [
                    'url' => $url,
                    'hybrid_analysis' => $hybridResult,
                    'virus_total' => $virusTotalResult,
                    'finail vedicat' => $summaryParts
       ];
          
            // Store results in an associative array
        }
        return response()->json($results);

        // Return the combined results as a JSON response
    }
}
