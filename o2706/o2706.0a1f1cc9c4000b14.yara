
rule o2706_0a1f1cc9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2706.0a1f1cc9c4000b14"
     cluster="o2706.0a1f1cc9c4000b14"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox ursu injector"
     md5_hashes="['97e81b471d70b83e6ce069d65bd8c9473ccd49b8','9bf0d091b15bccd25f5a84461bce0ca456d39623','201147b17e37a2e8184b92daeb4d61d1af3f4cb0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2706.0a1f1cc9c4000b14"

   strings:
      $hex_string = { 2e4a736f6e2e4c696e712e4a546f6b656e3e3e2e6765745f4973526561644f6e6c79006337646634373731393261656661383465366163393230363531643635 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
