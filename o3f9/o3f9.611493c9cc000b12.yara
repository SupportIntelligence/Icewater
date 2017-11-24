
rule o3f9_611493c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f9.611493c9cc000b12"
     cluster="o3f9.611493c9cc000b12"
     cluster_size="78"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy lyposit malicious"
     md5_hashes="['022a5f400921f56f8165bc80cff6ca98','1274738144dfbaf1377f99cc6080b6a5','a39a5106927d58997bcc06020f87162f']"

   strings:
      $hex_string = { 7531da95ef9fb7afe997f273b2458ab48650d9e712fe90aec2d1db9822b1fb6de2c67b6c5e881547e874260d4610ec2576c7a562c86e29489b5ad5588f30c5de }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
