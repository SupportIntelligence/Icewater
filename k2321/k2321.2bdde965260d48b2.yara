
rule k2321_2bdde965260d48b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2bdde965260d48b2"
     cluster="k2321.2bdde965260d48b2"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt vbkrypt"
     md5_hashes="['175ce7e5494d427673a4fe00a7066aa8','2efc0f0be350598ec7a082ce85df580e','d9e426e7657102a99744d53c36dfde87']"

   strings:
      $hex_string = { 8c89c0d4230c7f81a08a38201ca950fc253021488d62542849f242f0170bc433515c2a118864944cea8084d8f49efd1382fac5671001267a16e565a7e48d0a6a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
