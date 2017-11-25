
rule j3f0_3395be48dee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.3395be48dee31932"
     cluster="j3f0.3395be48dee31932"
     cluster_size="3"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious genericrxci"
     md5_hashes="['841d0ada5f4717c51fbf9d14583ffe78','c6d6057047032f4806eff1ebb305f59c','eb7b808ba2d12d66a3aaa02ca3334791']"

   strings:
      $hex_string = { 721d8b3989382bf203c203ca3bf273f285f674148a11881040414e75f7eb098a11881040414e75f70fb6314183fe1073570fb611c1ea02c1e6068db432010700 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
