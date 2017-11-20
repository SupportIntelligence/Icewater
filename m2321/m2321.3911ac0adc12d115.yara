
rule m2321_3911ac0adc12d115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3911ac0adc12d115"
     cluster="m2321.3911ac0adc12d115"
     cluster_size="59"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="palevo zegost razy"
     md5_hashes="['05bb306822be3eaa05ef40537da48f34','078616b9cc0329e0b4bcd0a3a3dd00d9','526af61a62927badcce81f6f128e64af']"

   strings:
      $hex_string = { 2160134d18f2c644edcc45dc8853dbf1af41ce7db9cb190f4bb696c92f3507f639ec4f02a836aa6a2b085e949038e8cfeeb87881e3ba8e779a2a3b26f97a9580 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
