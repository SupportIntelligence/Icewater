
rule n3e9_499eab49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499eab49c0000b12"
     cluster="n3e9.499eab49c0000b12"
     cluster_size="314"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['075725bea8db16cf2ba17b11c4d2e41c','0794b1a7a2c7535df2d43cc4bac83f59','40648d45c94ecd65a986081fd9eff6bd']"

   strings:
      $hex_string = { 01ffeeafab8a83badfd320d8a253de83763eb26abd59863f632c962764fc7b91eb626a2aab334094799434e866b744427e5eef0c27bfaa3c5b7a95b3e8a095fa }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
