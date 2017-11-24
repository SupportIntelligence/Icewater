
rule j3e9_34c6a5629935d595
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.34c6a5629935d595"
     cluster="j3e9.34c6a5629935d595"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd androm backdoor"
     md5_hashes="['516c9baa8e1d8c2db8a0d76027142aa7','567fe6058028c822bc9518fba2bcd18c','b88b10bbb46c6d6fabf00b4c5a6e4903']"

   strings:
      $hex_string = { e8193dee948a4ec4d2e94b3aa62f9dbff1170f03d1e0bbe5e57795af057afcad7cf6ddc15f7d35f8259f675f74d0a1c8de4ab9b0e74737dc0ce306f96d7372fe }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
