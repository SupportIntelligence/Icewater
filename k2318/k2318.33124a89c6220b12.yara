
rule k2318_33124a89c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33124a89c6220b12"
     cluster="k2318.33124a89c6220b12"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['e76c59108c68221da8de53ec4f1264e830acc781','7b6d1216081a7837bbb459fa47677a1a14b0a183','382dd6841adc6aba2a0d0866062b3aca560f0135']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33124a89c6220b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
