
rule m3e9_1b1262a4d8bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1b1262a4d8bb1932"
     cluster="m3e9.1b1262a4d8bb1932"
     cluster_size="350"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy coinminer comet"
     md5_hashes="['00746c685ab5139c2484f96aa9cfaa31','00bcffc1b39aac1f8f109b1babf584ba','0bb0ff31b91606ccf0dbd1f2908fbdea']"

   strings:
      $hex_string = { 5d030ecb50e5cd530dd47ff2839135225f05c627dccabd7c9d7d5763b9c464613bd16a001a55bc474fd63d82218eb71c779980b21d01eb2954ee77d7699b343e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
