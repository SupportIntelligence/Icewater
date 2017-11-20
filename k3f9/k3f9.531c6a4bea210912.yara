
rule k3f9_531c6a4bea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.531c6a4bea210912"
     cluster="k3f9.531c6a4bea210912"
     cluster_size="12"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vabushky small susp"
     md5_hashes="['0b4ccc18139a73da2c0b3f7367a29df1','235751ceac397fef4fa08ff7bb15a6ae','f8dad027b4afd1a2cdc9fd3f1af09ece']"

   strings:
      $hex_string = { 8d95385b9b0913339e4cfb7e05a5237aefa7dbc5164ced86aa3fbbd9bfc8a19ddb84eea39893773d17a9264ac4546902de7bb6d3e66d533bbe434d74f59a03c6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
