
rule k3f0_211433c5aa896f36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f0.211433c5aa896f36"
     cluster="k3f0.211433c5aa896f36"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="buzus keylogger ceeinject"
     md5_hashes="['0499b51519b940ab29a9c1042c453c99','4a8833b28096c632e31883e94f9844e8','f76f623f9f1cf9bdab4b3203a1569d45']"

   strings:
      $hex_string = { 26c00d0afa6f70655bf1ff62e0f22a6707778dced183d7163cf4f898a22ddb272ed3e89c3d9d3d1ddcab5d78f6acf71e1f53d95ec99b4a8bdfd0aa735f8247a4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
