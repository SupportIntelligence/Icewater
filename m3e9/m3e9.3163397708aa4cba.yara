
rule m3e9_3163397708aa4cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163397708aa4cba"
     cluster="m3e9.3163397708aa4cba"
     cluster_size="98"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0966596476dcf6917d75c1cc92a08076','2213910208de7248e2e2e029aa0feedc','a012e75951f1a68291dbb0578575a101']"

   strings:
      $hex_string = { ee545723e3329c9129a99f567962a7a9dc9eab17ac637bf33715339c8955449d7d9a8785fb9b942247355a482634893e664ee052c1d6510163fab7087d972818 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
