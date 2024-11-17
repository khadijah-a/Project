<?php

use App\Http\Controllers\dataset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UrlAnalysisController;
use App\Http\Controllers\TwilioController;
use App\Http\Controllers\ViresTotal;
use App\Http\Controllers\HybridAnalysisController;


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
Route::post('/webhook/whatsapp', [TwilioController::class, 'handleIncomingMessage']);
Route::post('/analyze-url-total', [ViresTotal::class, 'analyzeUrlViresTotal']);
Route::post('/scan-url-hybrid', [ViresTotal::class, 'HybridAnalysisScanUrl']);
Route::post('/analyze-url', [ViresTotal::class, 'analyzeUrl']);
Route::get('/analyze-urls', [dataset::class, 'analyzeUrl']);