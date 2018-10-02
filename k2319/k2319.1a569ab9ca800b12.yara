
rule k2319_1a569ab9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a569ab9ca800b12"
     cluster="k2319.1a569ab9ca800b12"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['39296ee0efece557045b75a882d536c1415615ce','5c905fa1b98a251c453e0863a4c5ef3a79547fdc','732fb63cd41e3c9dd97b2ac37c282c5cf3d649c9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a569ab9ca800b12"

   strings:
      $hex_string = { 32383f2839372c274627293a2830783130392c362e36364532292929627265616b7d3b7661722062385138713d7b276c3971273a66756e6374696f6e28522c70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
