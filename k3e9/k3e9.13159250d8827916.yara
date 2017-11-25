
rule k3e9_13159250d8827916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13159250d8827916"
     cluster="k3e9.13159250d8827916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['10c32748c93c7d7eed5221a7258ecd20','2b4549b53773285ec7a56c2b0e52ea4b','c63ac2ee2b7369c2e0987be7e6743b77']"

   strings:
      $hex_string = { 780d276068f93bd8b292164460dfe19b2fdcfbf6f5a2958f5e583a67e5c317964ee352102d7d844b70a681a54356c718eddbe92246cd3b1d63d4b1d3f1383fbf }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
