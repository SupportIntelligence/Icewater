
rule k3e9_291ced6d9a9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291ced6d9a9b0b12"
     cluster="k3e9.291ced6d9a9b0b12"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['38d19b3431cf8f3ce0b095f1cfa4f291','6b4dfff1087472cc5bcb45ff745300b1','e5d67fc898d24d2b98ae36d98abed4f5']"

   strings:
      $hex_string = { 9d1bc99a18c64a0f66a768b9911ab15eab54ca6502f2f6ba3f23a0adcff7990c0e9b25120ad40a4590461dac56e895d210b538522d8a510b633582588d304ec3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
