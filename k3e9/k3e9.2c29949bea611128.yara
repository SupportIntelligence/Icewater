
rule k3e9_2c29949bea611128
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2c29949bea611128"
     cluster="k3e9.2c29949bea611128"
     cluster_size="42"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader kryptik"
     md5_hashes="['0a4ebbf39cf6e390a481c7a3d4de5dc1','11e8053bcf2d669aa792b2dc4846260a','a1787b36a9b1154998ce6f5a5f1736fe']"

   strings:
      $hex_string = { 00190064006f00650073006e0027007400200073007500700070006f00720074002000730074007200650061006d0069006e0067002900410062006a00650063 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
