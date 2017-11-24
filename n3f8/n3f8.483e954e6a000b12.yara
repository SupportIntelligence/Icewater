
rule n3f8_483e954e6a000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.483e954e6a000b12"
     cluster="n3f8.483e954e6a000b12"
     cluster_size="156"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sandr androidos kasandra"
     md5_hashes="['02708f76ea5ed628cb713dff8b2376bd','03474954f1ca5d8e54f5c3b56ebba9a8','1d1de8d15e5d38a9881ca243ccadffa6']"

   strings:
      $hex_string = { fcee14020a88f1140102bcf4140102d0f514010294f614c0160084f7140100d88b150400a88d1500040103990610011001100110ca168180048c9215cb1601b4 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
