
rule k2377_61941a99c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.61941a99c2200932"
     cluster="k2377.61941a99c2200932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html wonka iframe"
     md5_hashes="['24aa794d21b1aabc466402898b6618e7','ac3ec3b100c825a04cf39906a19b2c68','d311ab7f9bbee835f9c9460b81b30091']"

   strings:
      $hex_string = { 6977612d423237685a365156642d77344657306b66646247506753566a754563666e6867304d22202f3e0d0a0d0a3c7469746c653e576562c3a1727568c3a17a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
