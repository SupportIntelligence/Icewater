
rule k3e9_0b9af3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b9af3a9c8000b12"
     cluster="k3e9.0b9af3a9c8000b12"
     cluster_size="46"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bqbqxwpi injector backdoor"
     md5_hashes="['186bd2551e2f35b34cf600af032f1784','1d54bb086ffcacc6fac24c3e65e5b571','b36b439b8b4b4e6397e3d139d6b42720']"

   strings:
      $hex_string = { 8847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840008bfff7d9ff248de067 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
