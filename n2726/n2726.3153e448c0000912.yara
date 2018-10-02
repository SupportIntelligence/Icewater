
rule n2726_3153e448c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2726.3153e448c0000912"
     cluster="n2726.3153e448c0000912"
     cluster_size="52"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi stantinko malicious"
     md5_hashes="['d6519e71ca7f87c2aa6cbb13da9e12804830305d','fbcbbc72d78b91a175c339606d984fa2bafde412','9b3f2a4b301095abce0661d720346f6c8b0e3782']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2726.3153e448c0000912"

   strings:
      $hex_string = { c7058232041063657300eb7cb839662801e83bf0ffff5156eb6e8d87598bffff83f86877630fb680fcbe0210ff2485e4be021048d923a8388bf18975f0c70628 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
