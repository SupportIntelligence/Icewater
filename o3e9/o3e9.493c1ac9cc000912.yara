
rule o3e9_493c1ac9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.493c1ac9cc000912"
     cluster="o3e9.493c1ac9cc000912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur malicious"
     md5_hashes="['afe0f9dd05a2397b1aab196aa1298d53','b8ab661cd49c5ebfd5ce37fba2ae1761','cadd1fe00eb2850f9848f5e10581b37a']"

   strings:
      $hex_string = { 8091ffab8192ffa2889eff9c8fa7ff939ebaff89accbff71cff8ff74c8f1ff89aacaffb97f85ffcf8962fffed6adfffcd1beffdb968bff331a0d8c351b0e3c3f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
