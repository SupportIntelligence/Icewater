
rule o3e9_0b1359b65852e392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b1359b65852e392"
     cluster="o3e9.0b1359b65852e392"
     cluster_size="256"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dlboost installmonster installmonstr"
     md5_hashes="['0080f8d5881513a682ae2c143fc1031a','00abf5ae6a859215bc2ab16d716c5731','0c9f05d60b486abef2a3652347ea3a13']"

   strings:
      $hex_string = { 3dddfbae53fab2a6a2308ec8f8077cb81bdf5e0654467d602ce1e2dde15c9a26b3b33042b3ac7f5ab7bddc08adec6ef2ac8fa4d7a66312c3370d4bcffbfa6ad7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
