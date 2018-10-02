
rule m26df_2b9722129ebb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26df.2b9722129ebb1932"
     cluster="m26df.2b9722129ebb1932"
     cluster_size="94"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family=""
     md5_hashes="['6b2ca8963ae1e732e39f93e0b779d823da35ec5c','37fe473454adbd7eae4742e4da166eb4c7d63a7f','24b78ad19e6744a2e774565034c84a0e440084a7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26df.2b9722129ebb1932"

   strings:
      $hex_string = { a7956abb884ed4490d22e280fc7832f0716796e8623f0200da12b901db1a6b9a5b63689ec685459dc916248c441efd371ff80cc152da9f7f202bc030f3ae143b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
