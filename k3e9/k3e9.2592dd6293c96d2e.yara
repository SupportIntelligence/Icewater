
rule k3e9_2592dd6293c96d2e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2592dd6293c96d2e"
     cluster="k3e9.2592dd6293c96d2e"
     cluster_size="26"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="snojan graftor malicious"
     md5_hashes="['06269b10e6b14fc522febb2b7353349d','0be697a5d47d8ea05a032146542d0105','bbe51580414106e8c2786224e7463ded']"

   strings:
      $hex_string = { f08955dc750d80fb307508ff4df88a1f47ebf339159c0e44007e110fb6c35650e80bd5ffff59596a015aeb0e8b0d900c44000fb6c38a044123c685c0741c837d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
