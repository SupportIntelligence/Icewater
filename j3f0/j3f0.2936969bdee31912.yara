
rule j3f0_2936969bdee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.2936969bdee31912"
     cluster="j3f0.2936969bdee31912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious malob crypt"
     md5_hashes="['3a92204dccc7c6c88e656c6c605d299c','3d2e67102d0db44212b71f6dae0f4fc5','b3a019f8a88e3ac77b318f59de148719']"

   strings:
      $hex_string = { 616c00555345522700880e77737072696e7466410057494e48545450c05c2537f8044f70656e0060e862db58059f2155e800178b3003f02bc08bfe66adc1e00c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
