
rule m3e9_131272299c12db11
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.131272299c12db11"
     cluster="m3e9.131272299c12db11"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt chinky vobfus"
     md5_hashes="['2130594f0fa81ecae1eebd51dad833c5','22456a40b58c12d0d310aeb1f2279894','fa1289371d472f0979bf74b937c37d74']"

   strings:
      $hex_string = { 50002f58ff0011f35015ebf2fdfb5cfffde6080010000040f4092bdefef4012b1aff0b36000800fbfd2358ff94080024012a23f0fef4632bdafef40a2bdcfe0b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
