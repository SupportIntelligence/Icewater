
rule n3e9_4996ea4cc0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4996ea4cc0000b12"
     cluster="n3e9.4996ea4cc0000b12"
     cluster_size="1901"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['00266e7a25eaa20c43fdeb01332b8fb6','0053ff02d7edf7e24f4ef5465334040d','060528056aa12c7641a0c478baf10162']"

   strings:
      $hex_string = { 01ffeeafab8a83badfd320d8a253de83763eb26abd59863f632c962764fc7b91eb626a2aab334094799434e866b744427e5eef0c27bfaa3c5b7a95b3e8a095fa }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
