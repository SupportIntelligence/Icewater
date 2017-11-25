
rule m2321_339893e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.339893e9c8800b12"
     cluster="m2321.339893e9c8800b12"
     cluster_size="24"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator rstdbjki gain"
     md5_hashes="['102dac0e2da87a68204710f233b5971f','128587c96983c24c44f357f9842884b8','79e03f63e5ac9b01fff0b2ce389c8c15']"

   strings:
      $hex_string = { ca2c92afbf9e4901d911dccd26416814cbbcfcf62a6971a1b95ede6b98c0b19383a8ebb433e3324d2e26880fe42790c40c531ee739b8288bdb7d70897663ab67 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
