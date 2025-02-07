import React, { useState, useEffect } from 'react';
import { Card,CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Cpu, Zap, ShieldCheck, Layers, Sparkles } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function AICloudDependencyAnalyzer() {
  const [url, setUrl] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [animationStage, setAnimationStage] = useState(0);

  const handleAnalyze = async () => {
    setAnimationStage(1);
    
    // Simulated AI analysis
    setTimeout(() => {
      const aiAnalysis = {
        overallRisk: 'Moderate',
        aiInsights: [
          'Detected potential cross-service vulnerability',
          'Recommended dependency optimization',
          'Identified unnecessary cloud permissions'
        ],
        securityMetrics: [
          { name: 'Authorization', score: 78 },
          { name: 'Data Encryption', score: 85 },
          { name: 'Network Security', score: 72 },
          { name: 'Compliance', score: 90 }
        ],
        cloudComplexity: [
          { service: 'Authentication', complexity: 65 },
          { service: 'Data Storage', complexity: 45 },
          { service: 'Network Routing', complexity: 80 }
        ]
      };
      
      setAnalysis(aiAnalysis);
      setAnimationStage(2);
    }, 2000);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-black text-white p-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-gray-700">
          <div className="flex items-center mb-6">
            <Cpu className="mr-3 text-blue-400" size={32} />
            <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-600">
              AI Cloud Dependency Analyzer
            </h1>
          </div>

          <div className="flex space-x-4">
            <Input
              type="text"
              placeholder="Enter URL for AI-powered analysis..."
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-grow bg-gray-700 border-gray-600 text-white"
            />
            <Button 
              onClick={handleAnalyze} 
              className="bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700"
            >
              <Zap className="mr-2" /> Analyze with AI
            </Button>
          </div>
        </div>

        {animationStage === 1 && (
          <div className="flex justify-center items-center space-x-4 text-blue-300 animate-pulse">
            <Sparkles /> 
            <span>AI is analyzing your cloud architecture...</span>
            <Sparkles />
          </div>
        )}

        {analysis && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* AI Insights */}
            <Card className="bg-gray-800 border-gray-700 text-white">
              <div className="p-6">
                <div className="flex items-center mb-4">
                  <ShieldCheck className="mr-2 text-green-400" />
                  <h2 className="text-xl font-semibold">AI Insights</h2>
                </div>
                <div className="space-y-3">
                  {analysis.aiInsights.map((insight, index) => (
                    <div key={index} className="flex items-center">
                      <Zap className="mr-2 text-yellow-400" size={16} />
                      <span>{insight}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Card>

            {/* Security Metrics */}
            <Card className="bg-gray-800 border-gray-700 text-white">
              <div className="p-6">
                <div className="flex items-center mb-4">
                  <Layers className="mr-2 text-blue-400" />
                  <h2 className="text-xl font-semibold">Security Metrics</h2>
                </div>
                <ResponsiveContainer width="100%" height={250}>
                  <LineChart data={analysis.securityMetrics}>
                    <XAxis dataKey="name" stroke="#4b5563" />
                    <YAxis stroke="#4b5563" />
                    <Tooltip />
                    <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={3} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Cloud Complexity */}
            <Card className="bg-gray-800 border-gray-700 text-white">
              <div className="p-6">
                <div className="flex items-center mb-4">
                  <Cpu className="mr-2 text-purple-400" />
                  <h2 className="text-xl font-semibold">Cloud Complexity</h2>
                </div>
                {analysis.cloudComplexity.map((service, index) => (
                  <div key={index} className="mb-3">
                    <div className="flex justify-between mb-1">
                      <span>{service.service}</span>
                      <span>{service.complexity}%</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2.5">
                      <div 
                        className="bg-gradient-to-r from-blue-500 to-purple-600 h-2.5 rounded-full" 
                        style={{width: `${service.complexity}%`}}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}