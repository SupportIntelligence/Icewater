
rule m3f0_11314ad6dba30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.11314ad6dba30912"
     cluster="m3f0.11314ad6dba30912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira bqcb miras"
     md5_hashes="['34d02e0ebe6ff2d32f61fcc2873d5ac5','49f2fd5cfb84f77d0d4389179480298e','fef7874dae773a560645adbfc0ad2be4']"

   strings:
      $hex_string = { f3b70f4d2adb3a4326d7364b2edf3e47a1d0314fa9d8b94085d4b5488dcaab5c9bc6a752970e805a9f0188d6900984de98058cd1a40d027608e9387e04e51471 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
