
rule k2321_6b34c6d599bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.6b34c6d599bb0912"
     cluster="k2321.6b34c6d599bb0912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="juched ganelp zusy"
     md5_hashes="['0ba096a5b43582e89dbc91f949cc382b','248e1b95cb76e4af83bf6e132747d1ff','edc1fd34034cbfb72f223361986d1285']"

   strings:
      $hex_string = { 51b5f01e4278b491f7ec25fc6393f6a9dab94f69e73ed1ced727a586b2eddcd618f48c84175ccfe0c13794106a5b2a1c432e740f41771638c60bf87d851ec08d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
