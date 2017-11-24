
rule k2321_0b10d852d3a30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b10d852d3a30916"
     cluster="k2321.0b10d852d3a30916"
     cluster_size="50"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['0518df9c532c05cdeefae2fd1e08e6f3','07464e2e4120cef3be4ed1fa81d78553','5644b4721628983fc29afaedcc202dd4']"

   strings:
      $hex_string = { 0d7fe86bac6f967aa7102f6ad5793b25d4b1e5a1789fe0eb46ffb39e657d076888dc09170a8b26fdebb99458fa3e9adb6987a85d3dfc768d9cbb40f7babd9734 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
