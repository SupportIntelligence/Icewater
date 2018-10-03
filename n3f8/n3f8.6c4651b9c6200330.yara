
rule n3f8_6c4651b9c6200330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6c4651b9c6200330"
     cluster="n3f8.6c4651b9c6200330"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos smsagent fakeinst"
     md5_hashes="['7c2a29244523a66ce212f2c0ed72cb74232d524a','870deca8baa11af4ae585c31aa08237dd4568e2e','1bc90dd6e9ce6afa93eaa5247063d3e39ddfb2ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6c4651b9c6200330"

   strings:
      $hex_string = { 646261636b54797065546f537472696e6700015b00156e756d6265724f66547261696c696e675a65726f7300022c20000f464545444241434b5f53504f4b454e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
