
rule k3e9_4324f85e9ebb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f85e9ebb1912"
     cluster="k3e9.4324f85e9ebb1912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['a1f48471d27411a3e35eae0b8e1c5088','b8e2c87343cbe7c16f51a4bc33ba9301','e42aee998a37e87afb2c66ca7b27e796']"

   strings:
      $hex_string = { f7de1bf646837df8007409ff75f8ff150c1000018bc6eb0233c05f5e5bc9c20400cccccccccc8bff558bec81ec1c020000a1f0600001538b5d08578945fc8d85 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
