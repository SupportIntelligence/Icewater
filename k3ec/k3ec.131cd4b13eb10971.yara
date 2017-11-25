
rule k3ec_131cd4b13eb10971
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.131cd4b13eb10971"
     cluster="k3ec.131cd4b13eb10971"
     cluster_size="75"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre wapomi"
     md5_hashes="['054744d331adeaa0aebd92ca80868e30','0a2d58e3bae698e628420d22b485d0df','49db050c488a96b4a374218cd1f38afe']"

   strings:
      $hex_string = { 1520f49f222c0540a82516ab24be2be1a9a0a6e496b186ba3f9f820a95cb551d5c69871252f3ae6e1301b88c6c71bbcc700a11061943f2ed6a4be65aa417d1c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
