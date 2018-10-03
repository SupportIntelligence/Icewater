
rule m2319_191e189dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.191e189dc6220b12"
     cluster="m2319.191e189dc6220b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker cryxos script"
     md5_hashes="['a07523ec06f8b386ef2aed332cfcac6d9f23b3d1','c0dd3436a88ed0afcfc9618bcbdbe808d6ba7a21','0592138be96132c731cf9d326a90f4a739aa9569']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.191e189dc6220b12"

   strings:
      $hex_string = { 3735292c3020302036707820236435393339327d2e6861732d6572726f72202e696e7075742d67726f75702d6164646f6e7b636f6c6f723a236239346134383b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
