exports.templateResource = (module, command, name) => {
  return {
    "Type": "AWS::Serverless::Function",
    "Properties": {
      "Handler": `src/modules/${module}/${command}.handler`,
      "Runtime": "nodejs14.x",
      "Architectures": [
        "x86_64"
      ],
      "MemorySize": 128,
      "Timeout": 100,
      "Policies": [
        "AWSLambdaBasicExecutionRole"
      ],
      "Events": {
        "SNSEvent": {
          "Type": "SNS",
          "Properties": {
            "Topic": {
              "Ref": "MainSNSTopic"
            },
            "FilterPolicy": {
              "command": [
                name
              ]
            }
          }
        }
      }
    }
  }
}