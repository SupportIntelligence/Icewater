
rule o3e9_16512c4ad6d26b9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16512c4ad6d26b9a"
     cluster="o3e9.16512c4ad6d26b9a"
     cluster_size="150"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster bundler installmonstr"
     md5_hashes="['01a0d32dd6b2d53e56ce34370bddd1ec','08e3fa7d26ffce19906520331375d39e','1cbafa9de9dcceafbf8bfba3c5fc66f5']"

   strings:
      $hex_string = { 3a57b44b27df6f1225d5d977bdc2b081e98b42822cb6659e00dd4e51c54afdbe0f6d9cad86a593aba3635808e3fc8de89a22a78753a97ec09d498444d33c2002 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
