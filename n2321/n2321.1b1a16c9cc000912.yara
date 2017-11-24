
rule n2321_1b1a16c9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.1b1a16c9cc000912"
     cluster="n2321.1b1a16c9cc000912"
     cluster_size="279"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="auslogics tweakbit unwanted"
     md5_hashes="['000dacf105b036b20f7acabb2332c249','00538dcd41659dc6cb927807c031d332','0ed7dbb1c70cdf47a33067eb26a39aeb']"

   strings:
      $hex_string = { a799cb8c66c138deca55b3f7198d8ec7d3638a259b6e13b4f0b8d93d3e79750df8680f224fc5907480a9a01e360e5ee3ea837b4886df7cf10c0a76c3b1dd1506 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
