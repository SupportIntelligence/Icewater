
rule o3e9_31bb2894ea008932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.31bb2894ea008932"
     cluster="o3e9.31bb2894ea008932"
     cluster_size="135"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious fynx kryptik"
     md5_hashes="['00419e760e254e9057c90817a7d51869','036f18da375ee2b034879fd9c4147b32','1f220e103fa856cd653de9e74ba5d1e0']"

   strings:
      $hex_string = { f439f839fc39003a0000083a0c3a103a143a183a0000203a243a200a200a00000000300a3c3a403a443a00004c3a0000543a583a5c3a600a643a683a600a700a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
