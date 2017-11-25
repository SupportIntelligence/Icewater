
rule k3e9_45634226f9b344b5
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45634226f9b344b5"
     cluster="k3e9.45634226f9b344b5"
     cluster_size="307"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0173555f1cee5f2386bf47ab0a199ede','06485f4bf41b5ede92d8f2df4a15e2fd','1e5aca14a7be8a4ee2c65b47b7227f7e']"

   strings:
      $hex_string = { 1a33c983f87a0f94c14981e1f73ff9ff81c10e000780894dfceb1bc745fc57000780eb12575083c6085651ff1590600001395dfc74128b75088b063bc3740950 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
