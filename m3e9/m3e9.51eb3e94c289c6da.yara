
rule m3e9_51eb3e94c289c6da
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.51eb3e94c289c6da"
     cluster="m3e9.51eb3e94c289c6da"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte optimuminstaller bundler"
     md5_hashes="['0199e9a9075c23df04b35ef664d345c2','05a1e6f633898fb2fdbe40e2b5d580b3','f735397b8017ebc378eb62cfd69cefa4']"

   strings:
      $hex_string = { 0001018174d32500010101750881e60000008075c45e5f5b33c0c38b42fc3ac3743684c074ef3ae3742784e474e7c1e8103ac3741584c074dc3ae3740684e474 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
