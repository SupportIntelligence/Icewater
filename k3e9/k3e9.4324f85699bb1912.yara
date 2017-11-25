
rule k3e9_4324f85699bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f85699bb1912"
     cluster="k3e9.4324f85699bb1912"
     cluster_size="233"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob genome"
     md5_hashes="['06afb4a103cc5748e90bba395bb824ec','0ad7be8e596179d91bf41f6cf5cfec2c','36af6a6dc16bdc9040ad08fc0d32e8e2']"

   strings:
      $hex_string = { f7de1bf646837df8007409ff75f8ff150c1000018bc6eb0233c05f5e5bc9c20400cccccccccc8bff558bec81ec1c020000a1f0600001538b5d08578945fc8d85 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
