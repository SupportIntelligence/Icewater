
rule k3e9_13959a50da227916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13959a50da227916"
     cluster="k3e9.13959a50da227916"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['6123df0426585e9fc28bedc58ce71468','6176847b6ca2041b819ae8674bda89ba','eec3578403b316e60bdac1d4c08784d8']"

   strings:
      $hex_string = { 5c71ecf6894d4a25eee9bb128f572a3d10898349c5313e7cb79295a1be0406af1b5815873740439d47f75b5ea3fec23f632b59ebdaea66bf1eae560e17dd4e38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
