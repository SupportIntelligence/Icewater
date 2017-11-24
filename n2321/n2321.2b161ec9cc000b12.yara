
rule n2321_2b161ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.2b161ec9cc000b12"
     cluster="n2321.2b161ec9cc000b12"
     cluster_size="152"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="imali johnnie adwaresig"
     md5_hashes="['00423d5d652c8edb5524390addbecf3e','0058c4cbfed41bef59504406f41a80b0','16ed4fe13ea9c4b4a33b46d364990be4']"

   strings:
      $hex_string = { 6b9e544f6ea3520ce5f77ca87459c040f976e2045def84945325a0144c604375612ea956dcea8aaf3c073515ebbfd40ab3372346cb13bc670e9f632ced78a5e8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
