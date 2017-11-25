
rule j3e9_29535ad4aa211916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.29535ad4aa211916"
     cluster="j3e9.29535ad4aa211916"
     cluster_size="3225"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="delf fileinfector hmjfa"
     md5_hashes="['002015dcb08a258baba34c25ec3c1c19','0029f94fb6a49d33b2a4d7ba883015e3','019c997cde4ab21891d1ec7def2f34ca']"

   strings:
      $hex_string = { d7b49223e4ed1f7cea53063cf2a8664c511afc67c603cac70424cb7ee6a495d678bc17486f268b00f70294752c09d240c31d4acc7d224950812d5fc030dda7f8 }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
