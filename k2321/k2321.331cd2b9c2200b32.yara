
rule k2321_331cd2b9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.331cd2b9c2200b32"
     cluster="k2321.331cd2b9c2200b32"
     cluster_size="3"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jqap small zbot"
     md5_hashes="['96417e0d0b02ee7249b6328441e5de1c','b8b4d3ea886208b96d84dedcbd31828c','ef420dad74d91258ab781d67d8bbad39']"

   strings:
      $hex_string = { 8ef272129f1ab44fed1fae7e2e5cdd099c4da6809736b266132932d861345264056e3b0856e6283da476d359e9a2f0bf3f46c448910e9d7a17e93eb5ad4ea853 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
