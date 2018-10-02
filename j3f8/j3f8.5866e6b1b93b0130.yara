
rule j3f8_5866e6b1b93b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5866e6b1b93b0130"
     cluster="j3f8.5866e6b1b93b0130"
     cluster_size="255"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos apprisk"
     md5_hashes="['d0e2edb00414b55ef5be2650149e87bb742c6c09','66c371b9740b63aeb3ddd6462cdeaa0f010764a2','b4cbf0a9895f5908396e15409d4b38ccb0fd791f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5866e6b1b93b0130"

   strings:
      $hex_string = { 616c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
