
rule k2321_31b162db999bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.31b162db999bd932"
     cluster="k2321.31b162db999bd932"
     cluster_size="57"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['07dbadf4131146697941893a0cc1cf72','0c6b3d06a8465637db58439eab2c327b','3e563adc44a7a1fed6cc903d22955c0a']"

   strings:
      $hex_string = { ec394694e3c4d8597cf6f2db8b706fd193faad45ed63e918111d23e6afa10ac7b8a4e05a1a0698d76cc2691405fa211fb29b5c4e047da02e5ce74f660244f585 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
