
rule m3e9_74445c8b354650da
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.74445c8b354650da"
     cluster="m3e9.74445c8b354650da"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus ajql pronny"
     md5_hashes="['08600485436daf4498c71b5b642b7b2b','7c5e3250ae357f18ece18b6acd37f5ce','f4cdd3ed76691007a7f7ca0a17444ea4']"

   strings:
      $hex_string = { 78ffec0808008a4400ecb637f426210f0803196cff086cff0d7c0204001a6cff1e3305000efce072fff401fc0dc61c330500230468ff801800801400210f0c03 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
