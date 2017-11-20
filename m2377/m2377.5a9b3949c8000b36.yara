
rule m2377_5a9b3949c8000b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.5a9b3949c8000b36"
     cluster="m2377.5a9b3949c8000b36"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['3a226e32a7ea738d31a3662071e32dc8','45831ebfc9ed76a913d20640832683f8','ffbe5bcd1ad3e1eaba4e705e2cb8ad4d']"

   strings:
      $hex_string = { 1e94a4530d672858ff23a521c852e28cacdcca1db38ed5a10bce8fb874cbaee298384fd612df80373ec40336b2e06e22d1543d9d9cc1810eb08bddf21862f30f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
