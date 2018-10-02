
rule k2318_2352dd1adee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2352dd1adee30b12"
     cluster="k2318.2352dd1adee30b12"
     cluster_size="64"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['74c0a5b7809a27cec4332548f89d502895dd029d','e16842a89668158990ca138fb2a4ad0652c20d98','5f9ca0a6e0c4f4062d37958a4250a129a307900b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2352dd1adee30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
